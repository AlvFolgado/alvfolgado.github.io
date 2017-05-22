/* jshint asi:true */

(function() {


  var demoContent = [
    {
      demo_link: 'https://github.com/AlvFolgado/WebRCEPoCs/tree/master/php/PHPCommandIPoC',
      img_link: 'https://raw.githubusercontent.com/AlvFolgado/WebRCEPoCs/master/php/PHPCommandIPoC/static/string.jpg',
      code_link: 'https://github.com/AlvFolgado/WebRCEPoCs/tree/master/php/PHPCommandIPoC',
      title: 'PHPCommandIPoC',
      core_tech: 'PHP',
      description: 'Learn the dangerous Function in PHP that let you perform Command and Argument Injections'
    }, {
      demo_link: 'https://github.com/AlvFolgado/WebRCEPoCs/tree/master/java/Deserialization',
      img_link: 'https://github.com/AlvFolgado/WebRCEPoCs/blob/master/java/Deserialization/DeserializationPoC/web/resources/java.jpg?raw=true',
      code_link: 'https://github.com/AlvFolgado/WebRCEPoCs/tree/master/java/Deserialization',
      title: 'Java Deserialization',
      core_tech: 'Java',
      description: 'Learn the dangers of Java uncontrolled deserialization with this PoC'
    }, {
      demo_link: 'https://github.com/AlvFolgado/WebRCEPoCs/tree/master/python/PoCDeserializationPickle',
      img_link: 'https://github.com/AlvFolgado/WebRCEPoCs/blob/master/python/PoCDeserializationPickle/PoC/picklepoc/static/pickles.jpg?raw=true',
      code_link: 'https://github.com/AlvFolgado/WebRCEPoCs/tree/master/python/PoCDeserializationPickle',
      title: 'Python Deserialization',
      core_tech: 'Python',
      description: 'Learn the dangerous functions in python that let deserialize data from an malicious input'
    } 
  ];

  contentInit(demoContent) 
  waitImgsLoad() 
}());


function contentInit(content) {
  // var htmlArr = [];
  // for (var i = 0; i < content.length; i++) {
  //     htmlArr.push('<div class="grid-item">')
  //     htmlArr.push('<a class="a-img" href="'+content[i].demo_link+'">')
  //     htmlArr.push('<img src="'+content[i].img_link+'">')
  //     htmlArr.push('</a>')
  //     htmlArr.push('<h3 class="demo-title">')
  //     htmlArr.push('<a href="'+content[i].demo_link+'">'+content[i].title+'</a>')
  //     htmlArr.push('</h3>')
  //     htmlArr.push('<p>主要技术：'+content[i].core_tech+'</p>')
  //     htmlArr.push('<p>'+content[i].description)
  //     htmlArr.push('<a href="'+content[i].code_link+'">源代码 <i class="fa fa-code" aria-hidden="true"></i></a>')
  //     htmlArr.push('</p>')
  //     htmlArr.push('</div>')
  // }
  // var htmlStr = htmlArr.join('')
  var htmlStr = ''
  for (var i = 0; i < content.length; i++) {
    htmlStr += '<div class="grid-item">' + '   <a class="a-img" href="' + content[i].demo_link + '">' + '       <img src="' + content[i].img_link + '">' + '   </a>' + '   <h3 class="demo-title">' + '       <a href="' + content[i].demo_link + '">' + content[i].title + '</a>' + '   </h3>' + '   <p>Tech：' + content[i].core_tech + '</p>' + '   <p>' + content[i].description + '       <a href="' + content[i].code_link + '">Link</a>' + '   </p>' + '</div>'
  }
  var grid = document.querySelector('.grid')
  grid.insertAdjacentHTML('afterbegin', htmlStr)
}


function waitImgsLoad() {
  var imgs = document.querySelectorAll('.grid img')
  var totalImgs = imgs.length
  var count = 0
  //console.log(imgs)
  for (var i = 0; i < totalImgs; i++) {
    if (imgs[i].complete) {
      //console.log('complete');
      count++
    } else {
      imgs[i].onload = function() {
        // alert('onload')
        count++
        //console.log('onload' + count)
        if (count == totalImgs) {
          //console.log('onload---bbbbbbbb')
          initGrid()
        }
      }
    }
  }
  if (count == totalImgs) {
    //console.log('---bbbbbbbb')
    initGrid()
  }
}


function initGrid() {
  var msnry = new Masonry('.grid', {
    // options
    itemSelector: '.grid-item',
    columnWidth: 250,
    isFitWidth: true,
    gutter: 20
  })
}
