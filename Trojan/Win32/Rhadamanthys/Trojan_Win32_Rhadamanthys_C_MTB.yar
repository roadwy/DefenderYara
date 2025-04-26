
rule Trojan_Win32_Rhadamanthys_C_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 03 88 45 ?? 45 ff 44 24 ?? 41 83 e1 ?? 85 d2 90 09 08 00 8b 5c 24 ?? 8a 44 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}