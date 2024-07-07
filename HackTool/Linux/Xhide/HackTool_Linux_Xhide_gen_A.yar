
rule HackTool_Linux_Xhide_gen_A{
	meta:
		description = "HackTool:Linux/Xhide.gen!A,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 48 69 64 65 20 2d 20 50 72 6f 63 65 73 73 20 46 61 6b 65 72 2c 20 62 79 20 53 63 68 69 7a 6f 70 72 65 6e 69 63 20 58 6e 75 78 65 72 20 52 65 73 65 61 72 63 68 20 28 63 29 20 32 30 30 32 } //4 XHide - Process Faker, by Schizoprenic Xnuxer Research (c) 2002
		$a_01_1 = {45 78 61 6d 70 6c 65 3a 20 25 73 20 2d 73 20 22 6b 6c 6f 67 64 20 2d 6d 20 30 22 20 2d 64 20 2d 70 20 74 65 73 74 2e 70 69 64 20 2e 2f 65 67 67 20 62 6f 74 2e 63 6f 6e 66 } //3 Example: %s -s "klogd -m 0" -d -p test.pid ./egg bot.conf
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}