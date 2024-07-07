
rule Trojan_Win32_Dridex_LAD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.LAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 cb ff 4d 90 01 01 75 90 01 01 89 55 90 01 01 2b 55 90 01 01 09 da 83 e0 90 01 01 09 d0 8b 55 90 01 01 59 aa 49 75 90 00 } //10
		$a_02_1 = {d3 c0 8a fc 8a e6 d3 cb ff 4d 90 01 01 75 90 01 01 57 83 e7 00 31 df 83 e0 00 09 f8 5f 59 aa 49 75 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}