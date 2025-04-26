
rule Trojan_Win32_Guloader_RPI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f ae e8 ff 31 [0-10] 5d [0-10] 81 f5 [0-10] 55 [0-10] 59 [0-10] 89 0c 37 [0-10] 4e [0-10] 4e [0-10] 4e [0-10] 4e 7d [0-10] 89 f9 [0-10] 51 [0-10] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}