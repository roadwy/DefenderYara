
rule Trojan_Win32_Stealer_DAE_MTB{
	meta:
		description = "Trojan:Win32/Stealer.DAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 0c 04 8d 14 80 8d 04 50 04 05 88 44 0c 04 41 81 f9 ?? ?? ?? ?? 74 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}