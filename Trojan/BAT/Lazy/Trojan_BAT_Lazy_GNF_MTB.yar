
rule Trojan_BAT_Lazy_GNF_MTB{
	meta:
		description = "Trojan:BAT/Lazy.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 52 43 6c 67 5a 62 6c 2e 65 78 65 } //1 eRClgZbl.exe
		$a_01_1 = {6d 5f 61 61 36 37 63 32 39 65 38 39 65 39 34 30 34 66 61 64 61 63 61 64 31 32 61 32 65 35 39 66 38 35 } //1 m_aa67c29e89e9404fadacad12a2e59f85
		$a_01_2 = {6d 5f 62 62 36 39 36 37 38 32 31 36 31 64 34 63 30 31 61 37 38 62 66 30 39 33 30 63 38 31 38 33 63 63 } //1 m_bb696782161d4c01a78bf0930c8183cc
		$a_01_3 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 } //1 aR3nbf8dQp2feLmk31
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}