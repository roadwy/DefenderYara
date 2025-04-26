
rule Trojan_Win32_Stealer_DAB_MTB{
	meta:
		description = "Trojan:Win32/Stealer.DAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 14 0c 80 c2 ?? 88 14 0c 41 83 f9 ?? 75 ec } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}