
rule Trojan_Win32_Guloader_SPBD_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 00 69 00 74 00 72 00 6f 00 73 00 74 00 61 00 72 00 63 00 68 00 5c 00 67 00 72 00 61 00 6e 00 6b 00 6f 00 67 00 6c 00 65 00 72 00 6e 00 65 00 2e 00 56 00 69 00 64 00 31 00 39 00 39 00 } //3 nitrostarch\grankoglerne.Vid199
		$a_01_1 = {41 00 6e 00 73 00 74 00 64 00 65 00 6c 00 69 00 67 00 68 00 65 00 64 00 65 00 6e 00 73 00 32 00 31 00 34 00 5c 00 2a 00 2e 00 6f 00 70 00 6b 00 } //2 Anstdelighedens214\*.opk
		$a_01_2 = {6a 00 61 00 63 00 74 00 69 00 74 00 61 00 74 00 65 00 64 00 2e 00 72 00 65 00 70 00 } //1 jactitated.rep
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}