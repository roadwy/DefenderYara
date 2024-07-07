
rule HackTool_MacOS_XHide_A_MTB{
	meta:
		description = "HackTool:MacOS/XHide.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 70 69 64 20 2e 2f 65 67 67 20 62 6f 74 2e 63 6f 6e 66 } //1 .pid ./egg bot.conf
		$a_00_1 = {46 61 6b 65 20 6e 61 6d 65 20 70 72 6f 63 65 73 73 } //1 Fake name process
		$a_01_2 = {58 48 69 64 65 20 2d 20 50 72 6f 63 65 73 73 20 46 61 6b 65 72 2c 20 62 79 20 53 63 68 69 7a 6f 70 72 65 6e 69 63 20 58 6e 75 78 65 72 20 52 65 73 65 61 72 63 68 } //1 XHide - Process Faker, by Schizoprenic Xnuxer Research
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}