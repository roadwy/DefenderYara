
rule HackTool_Win32_EarthWorm_SA{
	meta:
		description = "HackTool:Win32/EarthWorm.SA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_80_0 = {6c 63 78 5f 74 72 61 6e 20 2d 2d 6c 69 73 74 65 6e 70 6f 72 74 } //lcx_tran --listenport  1
		$a_80_1 = {73 73 6f 63 6b 73 64 20 2d 2d 6c 69 73 74 65 6e 70 6f 72 74 } //ssocksd --listenport  1
		$a_80_2 = {6c 63 78 5f 73 6c 61 76 65 20 2d 2d 72 65 66 68 6f 73 74 20 5b 72 65 66 5f 69 70 5d 20 2d 2d 72 65 66 70 6f 72 74 } //lcx_slave --refhost [ref_ip] --refport  1
		$a_80_3 = {72 63 73 6f 63 6b 73 } //rcsocks  1
		$a_80_4 = {72 73 73 6f 63 6b 73 } //rssocks  1
		$a_80_5 = {65 72 72 6f 72 20 6f 6e 20 63 6f 6e 6e 65 63 74 20 25 73 3a 25 64 20 5b 70 72 6f 74 6f 5f 69 6e 69 74 5f 63 6d 64 5f 72 63 73 6f 63 6b 65 74 5d } //error on connect %s:%d [proto_init_cmd_rcsocket]  1
		$a_80_6 = {68 74 74 70 3a 2f 2f 72 6f 6f 74 6b 69 74 65 72 2e 63 6f 6d 2f 65 61 72 74 68 77 72 6f 6d 2f } //http://rootkiter.com/earthwrom/  3
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*3) >=3
 
}