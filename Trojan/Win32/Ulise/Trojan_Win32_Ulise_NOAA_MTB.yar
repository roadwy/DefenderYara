
rule Trojan_Win32_Ulise_NOAA_MTB{
	meta:
		description = "Trojan:Win32/Ulise.NOAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 53 8b 4e 10 c1 e9 02 8b 76 0c 03 35 75 21 40 00 f3 a5 5b 5e 83 c6 28 4b 75 e5 0f 31 bb f4 40 40 00 bf 68 21 40 00 b9 04 00 00 00 3c 3d 76 04 2c 3d eb f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}