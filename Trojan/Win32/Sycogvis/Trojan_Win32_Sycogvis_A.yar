
rule Trojan_Win32_Sycogvis_A{
	meta:
		description = "Trojan:Win32/Sycogvis.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {3b de 75 05 8d 75 f8 2b cb 6a 00 e8 ?? ?? ?? ?? 31 5d fc 8b ce d3 7d fc 8a 4d fc d3 25 08 29 02 10 5f } //1
		$a_00_1 = {83 fe 01 75 35 8b 45 08 89 45 fc 8b 4d fc 33 c1 89 55 fc 89 45 08 8b 45 08 89 5d fc 09 05 7c 29 02 10 57 89 7d fc 8d 85 ec fd ff ff 50 ff 75 20 ff 75 f8 } //1
		$a_00_2 = {8b 45 08 89 45 fc 8a 4d fc d3 f8 89 7e 08 89 55 fc 66 c7 06 09 00 89 45 08 8b 45 08 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}