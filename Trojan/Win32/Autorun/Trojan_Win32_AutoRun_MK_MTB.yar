
rule Trojan_Win32_AutoRun_MK_MTB{
	meta:
		description = "Trojan:Win32/AutoRun.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 63 61 6c 6c 62 61 63 6b 2e 68 6f 73 74 73 77 69 73 73 2e 63 6f 6d 2f 64 69 72 2e 67 69 66 } //15 http://callback.hostswiss.com/dir.gif
		$a_01_1 = {68 74 74 70 3a 2f 2f 63 61 6c 6c 62 61 63 6b 2e 77 30 6e 64 65 72 6b 69 64 73 2e 69 6e 66 6f 2f 64 69 72 2e 67 69 66 } //15 http://callback.w0nderkids.info/dir.gif
		$a_01_2 = {68 74 74 70 3a 2f 2f 63 61 6c 6c 62 61 63 6b 2e 62 65 65 63 69 74 79 73 65 61 72 63 68 2e 63 6f 6d 2f 64 69 72 2e 67 69 66 } //15 http://callback.beecitysearch.com/dir.gif
		$a_01_3 = {74 32 66 73 79 73 74 65 6d } //5 t2fsystem
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*15+(#a_01_2  & 1)*15+(#a_01_3  & 1)*5) >=50
 
}