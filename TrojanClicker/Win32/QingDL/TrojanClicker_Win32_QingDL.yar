
rule TrojanClicker_Win32_QingDL{
	meta:
		description = "TrojanClicker:Win32/QingDL,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 39 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 63 70 72 2e 69 6e 69 } //1 %s\cpr.ini
		$a_01_1 = {25 73 5c 6b 77 62 75 66 2e 69 6e 69 } //4 %s\kwbuf.ini
		$a_01_2 = {25 73 5c 74 6f 6f 6c 73 65 74 2e 69 6e 69 } //4 %s\toolset.ini
		$a_00_3 = {7b 00 38 00 34 00 31 00 42 00 32 00 42 00 36 00 35 00 2d 00 31 00 31 00 38 00 44 00 2d 00 34 00 46 00 46 00 32 00 2d 00 41 00 44 00 36 00 33 00 2d 00 34 00 43 00 46 00 46 00 34 00 34 00 42 00 38 00 42 00 36 00 38 00 46 00 7d 00 } //5 {841B2B65-118D-4FF2-AD63-4CFF44B8B68F}
		$a_01_4 = {7b 44 46 43 42 33 34 42 36 2d 39 30 32 44 2d 34 32 36 45 2d 41 45 32 42 2d 31 42 32 39 34 41 45 31 39 46 34 46 7d } //5 {DFCB34B6-902D-426E-AE2B-1B294AE19F4F}
		$a_01_5 = {42 61 69 64 75 58 6d 6c 4d 61 70 70 69 6e 67 20 77 69 6c 64 66 69 72 65 20 25 64 } //10 BaiduXmlMapping wildfire %d
		$a_01_6 = {63 6e 73 2e 33 37 32 31 2e 63 6f 6d 2f 63 6e 73 2e 64 6c } //5 cns.3721.com/cns.dl
		$a_01_7 = {45 64 69 74 69 6f 6e 3d 31 26 42 61 72 4e 61 6d 65 3d 62 61 69 64 75 26 4e 61 6d 65 3d } //5 Edition=1&BarName=baidu&Name=
		$a_01_8 = {73 68 6f 77 5f 77 65 61 74 68 65 72 28 22 } //1 show_weather("
		$a_01_9 = {68 74 74 70 3a 2f 2f 63 6c 75 62 2e 62 6f 6f 6b 2e 73 69 6e 61 2e 63 6f 6d 2e 63 6e 2f 62 6f 6f 6b 73 65 61 72 63 68 2f 62 6f 6f 6b 73 65 61 72 63 68 2e 70 68 70 3f 6b 77 3d 25 73 } //1 http://club.book.sina.com.cn/booksearch/booksearch.php?kw=%s
		$a_01_10 = {68 74 74 70 3a 2f 2f 64 2e 73 6f 67 6f 75 2e 63 6f 6d 2f 6d 75 73 69 63 2e 73 6f 3f 71 75 65 72 79 3d 25 73 } //1 http://d.sogou.com/music.so?query=%s
		$a_01_11 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 65 6e 65 74 2e 63 6f 6d 2e 63 6e 2f 73 65 61 72 63 68 2e 70 68 70 3f 6b 65 79 77 6f 72 64 3d 25 73 } //1 http://download.enet.com.cn/search.php?keyword=%s
		$a_01_12 = {68 74 74 70 3a 2f 2f 66 69 6e 64 2e 76 65 72 79 63 64 2e 63 6f 6d 2f 66 6f 6c 64 65 72 73 3f 63 61 74 3d 6d 6f 76 69 65 26 6b 77 3d 25 73 } //1 http://find.verycd.com/folders?cat=movie&kw=%s
		$a_01_13 = {68 74 74 70 3a 2f 2f 66 6f 6f 2e 77 39 37 2e 63 6e 2f 64 61 74 61 2f 66 69 6c 65 2f 6b 77 62 75 66 2e 69 6e 69 } //1 http://foo.w97.cn/data/file/kwbuf.ini
		$a_01_14 = {68 74 74 70 3a 2f 2f 66 6f 6f 2e 77 39 37 2e 63 6e 2f 53 6f 66 74 49 6e 74 65 72 46 61 63 65 2f 53 65 61 72 63 68 4e 75 6d 2e 61 73 70 78 } //1 http://foo.w97.cn/SoftInterFace/SearchNum.aspx
		$a_01_15 = {68 74 74 70 3a 2f 2f 67 61 6d 65 73 2e 65 6e 65 74 2e 63 6f 6d 2e 63 6e 2f 61 72 74 69 63 6c 65 2f 53 65 61 72 63 68 43 61 74 65 67 6f 72 79 2e 70 68 70 3f 6b 65 79 3d 25 73 } //1 http://games.enet.com.cn/article/SearchCategory.php?key=%s
		$a_01_16 = {68 74 74 70 3a 2f 2f 68 74 6d 6c 2e 68 6a 73 6d 2e 74 6f 6d 2e 63 6f 6d 2f 3f 6d 6f 64 3d 62 6f 6f 6b 26 61 63 74 3d 61 6e 6f 6e 73 65 61 72 63 68 26 6b 65 79 3d 25 73 } //1 http://html.hjsm.tom.com/?mod=book&act=anonsearch&key=%s
		$a_01_17 = {68 74 74 70 3a 2f 2f 69 6d 61 67 65 2e 73 6f 73 6f 2e 63 6f 6d 2f 69 6d 61 67 65 2e 63 67 69 3f 77 3d 25 73 } //1 http://image.soso.com/image.cgi?w=%s
		$a_01_18 = {68 74 74 70 3a 2f 2f 69 6d 61 67 65 73 2e 67 6f 6f 67 6c 65 2e 63 6e 2f 69 6d 61 67 65 73 3f 71 3d 25 73 } //1 http://images.google.cn/images?q=%s
		$a_01_19 = {68 74 74 70 3a 2f 2f 69 6d 67 2e 7a 68 6f 6e 67 73 6f 75 2e 63 6f 6d 2f 69 3f 77 3d 25 73 } //1 http://img.zhongsou.com/i?w=%s
		$a_01_20 = {68 74 74 70 3a 2f 2f 6b 73 2e 70 63 67 61 6d 65 73 2e 63 6f 6d 2e 63 6e 2f 67 61 6d 65 73 5f 69 6e 64 65 78 2e 6a 73 70 3f 71 3d 25 73 } //1 http://ks.pcgames.com.cn/games_index.jsp?q=%s
		$a_01_21 = {68 74 74 70 3a 2f 2f 6b 73 2e 70 63 6f 6e 6c 69 6e 65 2e 63 6f 6d 2e 63 6e 2f 69 6e 64 65 78 2e 6a 73 70 3f 71 78 3d 64 6f 77 6e 6c 6f 61 64 26 71 3d 25 73 } //1 http://ks.pconline.com.cn/index.jsp?qx=download&q=%s
		$a_01_22 = {68 74 74 70 3a 2f 2f 6d 70 33 2e 62 61 69 64 75 2e 63 6f 6d 2f 6d 3f 74 6e 3d 62 61 69 64 75 6d 70 33 6c 79 72 69 63 26 63 74 3d } //1 http://mp3.baidu.com/m?tn=baidump3lyric&ct=
		$a_01_23 = {68 74 74 70 3a 2f 2f 6d 70 33 2e 62 61 69 64 75 2e 63 6f 6d 2f 6d 3f 74 6e 3d } //1 http://mp3.baidu.com/m?tn=
		$a_01_24 = {68 74 74 70 3a 2f 2f 6d 70 33 2e 7a 68 6f 6e 67 73 6f 75 2e 63 6f 6d 2f 6d 3f 77 3d 25 73 } //1 http://mp3.zhongsou.com/m?w=%s
		$a_01_25 = {68 74 74 70 3a 2f 2f 6d 75 73 69 63 2e 63 6e 2e 79 61 68 6f 6f 2e 63 6f 6d 2f 6c 79 72 69 63 2e 68 74 6d 6c 3f 70 3d 25 73 } //1 http://music.cn.yahoo.com/lyric.html?p=%s
		$a_01_26 = {68 74 74 70 3a 2f 2f 6d 75 73 69 63 2e 73 6f 73 6f 2e 63 6f 6d 2f 71 3f 73 63 3d 6d 75 73 26 77 3d 25 73 } //1 http://music.soso.com/q?sc=mus&w=%s
		$a_01_27 = {68 74 74 70 3a 2f 2f 70 2e 69 61 73 6b 2e 63 6f 6d 2f 70 3f 6b 3d 25 73 } //1 http://p.iask.com/p?k=%s
		$a_01_28 = {68 74 74 70 3a 2f 2f 70 2e 7a 68 6f 6e 67 73 6f 75 2e 63 6f 6d 2f 70 3f 77 3d 25 73 } //1 http://p.zhongsou.com/p?w=%s
		$a_01_29 = {68 74 74 70 3a 2f 2f 70 69 63 2e 73 6f 67 6f 75 2e 63 6f 6d 2f 70 69 63 73 3f 71 75 65 72 79 3d 25 73 } //1 http://pic.sogou.com/pics?query=%s
		$a_01_30 = {68 74 74 70 3a 2f 2f 73 65 61 72 63 68 2e 31 37 31 37 33 2e 63 6f 6d 2f 69 6e 64 65 78 2e 6a 73 70 3f 6b 65 79 77 6f 72 64 3d 25 73 } //1 http://search.17173.com/index.jsp?keyword=%s
		$a_01_31 = {68 74 74 70 3a 2f 2f 73 65 61 72 63 68 2e 62 74 63 68 69 6e 61 2e 6e 65 74 2f 73 65 61 72 63 68 2e 70 68 70 3f 71 75 65 72 79 3d 25 73 } //1 http://search.btchina.net/search.php?query=%s
		$a_01_32 = {68 74 74 70 3a 2f 2f 73 65 61 72 63 68 2e 63 72 73 6b 79 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 61 73 70 3f 73 54 79 70 65 3d 52 65 73 4e 61 6d 65 26 6b 65 79 77 6f 72 64 3d 25 73 } //1 http://search.crsky.com/search.asp?sType=ResName&keyword=%s
		$a_01_33 = {68 74 74 70 3a 2f 2f 73 65 61 72 63 68 2e 64 61 6e 67 64 61 6e 67 2e 63 6f 6d 2f 64 61 6e 67 64 61 6e 67 2e 64 6c 6c 3f 6d 6f 64 65 3d 31 30 32 30 26 63 61 74 61 6c 6f 67 3d 31 30 30 26 6b 65 79 31 3d 25 73 } //1 http://search.dangdang.com/dangdang.dll?mode=1020&catalog=100&key1=%s
		$a_01_34 = {68 74 74 70 3a 2f 2f 73 65 61 72 63 68 2e 67 61 6d 65 73 2e 73 69 6e 61 2e 63 6f 6d 2e 63 6e 2f 63 67 69 2d 62 69 6e 2f 67 61 6d 65 5f 73 65 61 72 63 68 2f 67 61 6d 65 5f 64 65 61 6c 2e 63 67 69 3f 6b 65 79 77 6f 72 64 73 3d 25 73 } //1 http://search.games.sina.com.cn/cgi-bin/game_search/game_deal.cgi?keywords=%s
		$a_01_35 = {68 74 74 70 3a 2f 2f 73 65 61 72 63 68 2e 6e 65 77 68 75 61 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 61 73 70 3f 4b 65 79 77 6f 72 64 3d 25 73 } //1 http://search.newhua.com/search.asp?Keyword=%s
		$a_01_36 = {68 74 74 70 3a 2f 2f 73 65 61 72 63 68 2e 75 6e 69 6f 6e 2e 79 61 68 6f 6f 2e 63 6f 6d 2e 63 6e 2f 63 6c 69 63 6b 2f 73 65 61 72 63 68 2e 68 74 6d 3f 6d 3d } //1 http://search.union.yahoo.com.cn/click/search.htm?m=
		$a_01_37 = {68 74 74 70 3a 2f 2f 76 2e 62 61 69 64 75 2e 63 6f 6d 2f 73 72 68 2e 70 68 70 3f 74 6e 3d 6f 6c 69 76 65 72 31 5f 64 67 26 77 6f 72 64 3d 25 73 } //1 http://v.baidu.com/srh.php?tn=oliver1_dg&word=%s
		$a_01_38 = {68 74 74 70 3a 2f 2f 76 2e 69 61 73 6b 2e 63 6f 6d 2f 76 3f 74 61 67 3d 26 6b 3d 25 73 } //1 http://v.iask.com/v?tag=&k=%s
		$a_01_39 = {68 74 74 70 3a 2f 2f 77 65 61 74 68 65 72 2e 32 36 35 2e 63 6f 6d 2f 25 73 } //1 http://weather.265.com/%s
		$a_01_40 = {68 74 74 70 3a 2f 2f 77 65 61 74 68 65 72 2e 32 36 35 2e 63 6f 6d 2f 67 65 74 5f 77 65 61 74 68 65 72 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 67 65 74 5f 63 69 74 79 } //1 http://weather.265.com/get_weather.php?action=get_city
		$a_01_41 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 61 69 64 75 2e 63 6f 6d 2f 62 61 69 64 75 3f 74 6e 3d } //1 http://www.baidu.com/baidu?tn=
		$a_01_42 = {68 74 74 70 3a 2f 2f 77 77 77 2e 64 61 79 62 74 2e 63 6f 6d 2f 71 75 65 72 79 2e 61 73 70 3f 71 3d 25 73 } //1 http://www.daybt.com/query.asp?q=%s
		$a_01_43 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6e 2f 73 65 61 72 63 68 3f 71 3d 25 73 } //1 http://www.google.cn/search?q=%s
		$a_01_44 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 61 73 6b 2e 63 6f 6d 2f 73 3f 6b 3d 25 73 } //1 http://www.iask.com/s?k=%s
		$a_01_45 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 63 69 62 61 2e 63 6f 6d 2f 73 65 61 72 63 68 3f 73 3d 25 73 } //1 http://www.iciba.com/search?s=%s
		$a_01_46 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 70 2e 63 6f 6d 2e 63 6e 2f 69 64 63 61 72 64 2e 70 68 70 3f 71 3d 25 73 } //1 http://www.ip.com.cn/idcard.php?q=%s
		$a_01_47 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 70 2e 63 6f 6d 2e 63 6e 2f 69 70 2e 70 68 70 3f 71 3d 25 73 } //1 http://www.ip.com.cn/ip.php?q=%s
		$a_01_48 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 70 2e 63 6f 6d 2e 63 6e 2f 6d 6f 62 69 6c 65 2e 70 68 70 3f 71 3d 25 73 } //1 http://www.ip.com.cn/mobile.php?q=%s
		$a_01_49 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 70 2e 63 6f 6d 2e 63 6e 2f 74 65 6c 2e 70 68 70 3f 71 3d 25 73 } //1 http://www.ip.com.cn/tel.php?q=%s
		$a_01_50 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 6f 67 6f 75 2e 63 6f 6d 2f 77 65 62 3f 71 75 65 72 79 3d 25 73 } //1 http://www.sogou.com/web?query=%s
		$a_01_51 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 6f 73 6f 2e 63 6f 6d 2f 71 3f 77 3d 25 73 } //1 http://www.soso.com/q?w=%s
		$a_01_52 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 71 31 32 31 2e 63 6f 6d 2e 63 6e 2f } //1 http://www.tq121.com.cn/
		$a_01_53 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 6f 73 73 73 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 61 73 70 78 3f 71 3d 25 73 } //1 http://www.wosss.com/search.aspx?q=%s
		$a_01_54 = {68 74 74 70 3a 2f 2f 77 77 77 2e 79 6f 64 61 6f 2e 63 6f 6d 2f 73 65 61 72 63 68 3f 75 65 3d 75 74 66 38 26 71 3d 25 73 } //1 http://www.yodao.com/search?ue=utf8&q=%s
		$a_01_55 = {68 74 74 70 3a 2f 2f 79 63 2e 62 6f 6f 6b 2e 73 6f 68 75 2e 63 6f 6d 2f 73 65 72 69 65 73 5f 6c 69 73 74 2e 70 68 70 3f 73 65 6c 65 63 74 3d 31 26 74 65 78 74 3d 25 73 } //1 http://yc.book.sohu.com/series_list.php?select=1&text=%s
		$a_01_56 = {68 74 74 70 3a 2f 2f 79 73 2e 63 6e 2e 79 61 68 6f 6f 2e 63 6f 6d 2f 6d 6f 68 75 2f 69 6e 64 65 78 2e 68 74 6d 6c 3f 70 3d 25 73 } //1 http://ys.cn.yahoo.com/mohu/index.html?p=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_00_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*10+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1+(#a_01_30  & 1)*1+(#a_01_31  & 1)*1+(#a_01_32  & 1)*1+(#a_01_33  & 1)*1+(#a_01_34  & 1)*1+(#a_01_35  & 1)*1+(#a_01_36  & 1)*1+(#a_01_37  & 1)*1+(#a_01_38  & 1)*1+(#a_01_39  & 1)*1+(#a_01_40  & 1)*1+(#a_01_41  & 1)*1+(#a_01_42  & 1)*1+(#a_01_43  & 1)*1+(#a_01_44  & 1)*1+(#a_01_45  & 1)*1+(#a_01_46  & 1)*1+(#a_01_47  & 1)*1+(#a_01_48  & 1)*1+(#a_01_49  & 1)*1+(#a_01_50  & 1)*1+(#a_01_51  & 1)*1+(#a_01_52  & 1)*1+(#a_01_53  & 1)*1+(#a_01_54  & 1)*1+(#a_01_55  & 1)*1+(#a_01_56  & 1)*1) >=70
 
}