
rule Trojan_AndroidOS_SmsSend_GH_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSend.GH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 2e 6d 77 6f 72 6c 64 2e 76 6e 2f 4d 57 6f 72 6c 64 33 30 2f 64 61 74 61 32 30 2e 78 6d 3f 61 3d 67 65 74 69 70 26 67 3d 33 26 73 65 78 3d 41 6e 64 72 6f 69 64 } //2 http://m.mworld.vn/MWorld30/data20.xm?a=getip&g=3&sex=Android
		$a_01_1 = {53 4d 53 5f 53 45 4e 54 5f } //2 SMS_SENT_
		$a_01_2 = {72 65 73 6f 75 72 63 65 2e 64 61 74 } //1 resource.dat
		$a_01_3 = {61 53 4d 53 } //1 aSMS
		$a_01_4 = {e1 bb a8 6e 67 20 64 e1 bb a5 6e 67 20 c4 91 c3 a3 20 c4 91 c6 b0 e1 bb a3 63 20 6b c3 ad 63 68 20 68 6f e1 ba a1 74 20 74 68 c3 a0 6e 68 20 63 c3 b4 6e 67 2c 20 63 68 c3 ba 63 20 62 e1 ba a1 6e 20 76 75 69 20 76 e1 ba bb 21 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}