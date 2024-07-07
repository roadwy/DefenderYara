
rule Trojan_Win32_Dridex_PH_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 90 01 01 ff 90 02 04 6a 00 89 90 02 02 29 90 01 01 09 90 01 01 89 90 01 01 5d 81 90 01 05 8f 90 01 02 03 90 01 02 aa 49 75 90 00 } //1
		$a_02_1 = {d3 c0 8a fc 8a e6 d3 cb ff 90 02 04 89 90 02 02 33 90 02 04 83 90 02 04 8b 90 02 02 8f 90 02 02 8b 90 02 02 aa 49 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}