
rule Trojan_BAT_AgentTesla_AABN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AABN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {51 00 75 00 61 00 6e 00 4c 00 79 00 56 00 61 00 74 00 4c 00 69 00 65 00 75 00 58 00 61 00 79 00 44 00 75 00 6e 00 67 00 } //01 00  QuanLyVatLieuXayDung
		$a_01_1 = {61 39 62 66 38 63 62 38 2d 61 33 61 34 2d 34 30 31 37 2d 39 33 37 32 2d 31 65 38 31 34 33 39 61 38 38 63 31 } //01 00  a9bf8cb8-a3a4-4017-9372-1e81439a88c1
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}