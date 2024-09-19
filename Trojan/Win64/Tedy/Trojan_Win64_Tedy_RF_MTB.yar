
rule Trojan_Win64_Tedy_RF_MTB{
	meta:
		description = "Trojan:Win64/Tedy.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 73 01 0f 1f 40 00 0f 1f 84 00 00 00 00 00 49 8b 14 de 49 8b c5 66 0f 1f 84 00 00 00 00 00 0f b6 0c 02 48 ff c0 41 3a 4c 04 ff 75 1d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}