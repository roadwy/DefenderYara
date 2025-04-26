
rule PWS_Win32_QQpass_GT{
	meta:
		description = "PWS:Win32/QQpass.GT,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {6a 61 76 61 73 63 72 69 70 74 3a 66 6f 72 28 76 61 72 20 43 3d 30 3b 43 3c 71 5f 61 55 69 6e 4c 69 73 74 2e 6c 65 6e 67 74 68 3b 43 2b 2b 29 7b 76 61 72 20 44 3d 71 5f 61 55 69 6e 4c 69 73 74 5b 43 5d 3b 64 6f 63 75 6d 65 6e 74 2e 77 72 69 74 65 28 44 2e 75 69 6e 2b 22 2c 22 2b 44 2e 6b 65 79 2b 22 5b } //2 javascript:for(var C=0;C<q_aUinList.length;C++){var D=q_aUinList[C];document.write(D.uin+","+D.key+"[
		$a_01_1 = {78 75 69 2e 70 74 6c 6f 67 69 6e 32 2e 71 71 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 71 6c 6f 67 69 6e 3f 64 6f 6d 61 69 6e 3d 71 71 2e 63 6f 6d 26 6c 61 6e 67 3d 32 30 35 32 26 71 74 61 72 67 65 74 3d 30 26 6a 75 6d 70 6e 61 6d 65 3d 26 70 74 63 73 73 3d 26 70 61 72 61 6d 3d 75 31 } //2 xui.ptlogin2.qq.com/cgi-bin/qlogin?domain=qq.com&lang=2052&qtarget=0&jumpname=&ptcss=&param=u1
		$a_01_2 = {78 6e 6f 74 65 2e 63 6e 2f 61 70 69 2f 6e 6f 74 65 2f 73 61 76 65 2f } //2 xnote.cn/api/note/save/
		$a_01_3 = {26 63 6c 69 65 6e 74 6b 65 79 3d } //1 &clientkey=
		$a_01_4 = {35 30 39 30 35 30 36 39 } //1 50905069
		$a_01_5 = {6d 61 69 6c 74 6f 3a } //1 mailto:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}