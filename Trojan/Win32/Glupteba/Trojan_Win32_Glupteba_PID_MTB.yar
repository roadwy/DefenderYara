
rule Trojan_Win32_Glupteba_PID_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 04 24 00 00 00 00 8b 44 24 ?? 89 04 24 8b 44 24 44 31 04 24 8b 04 24 8b 4c 24 40 89 01 83 c4 3c c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}