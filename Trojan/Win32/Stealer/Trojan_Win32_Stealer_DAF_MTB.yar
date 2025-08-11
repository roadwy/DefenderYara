
rule Trojan_Win32_Stealer_DAF_MTB{
	meta:
		description = "Trojan:Win32/Stealer.DAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 4d 0c 03 08 89 4d f8 8b 45 08 8b 4d 0c 03 48 10 89 4d ec 8b 45 f8 3b 45 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}