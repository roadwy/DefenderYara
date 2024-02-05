
rule Trojan_Win32_Dridex_LBN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.LBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 cb ff 4d 90 01 01 75 f3 89 75 90 01 01 33 75 90 01 01 09 de 83 e0 00 09 f0 8b 75 90 01 01 8f 45 90 01 01 8b 4d 90 01 01 aa 49 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}