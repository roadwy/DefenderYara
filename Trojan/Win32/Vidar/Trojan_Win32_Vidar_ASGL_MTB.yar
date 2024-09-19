
rule Trojan_Win32_Vidar_ASGL_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 02 83 45 ec 04 6a 00 e8 } //4
		$a_03_1 = {8b 45 ec 3b 45 ?? 72 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}