
rule Trojan_BAT_GravityRat_K_MTB{
	meta:
		description = "Trojan:BAT/GravityRat.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 11 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 41 56 } //1 GetAV
		$a_01_1 = {67 65 74 5f 4d 61 63 69 64 } //1 get_Macid
		$a_01_2 = {67 65 74 5f 43 70 75 69 64 } //1 get_Cpuid
		$a_01_3 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //1 get_MachineName
		$a_01_4 = {67 65 74 5f 46 75 6c 6c 4e 61 6d 65 } //1 get_FullName
		$a_01_5 = {67 65 74 5f 55 73 65 72 44 6f 6d 61 69 6e 4e 61 6d 65 } //1 get_UserDomainName
		$a_01_6 = {67 65 74 5f 55 73 65 72 4e 61 6d 65 } //1 get_UserName
		$a_01_7 = {67 65 74 5f 50 63 6e 61 6d 65 } //1 get_Pcname
		$a_01_8 = {67 65 74 5f 4f 73 76 65 72 73 69 6f 6e } //1 get_Osversion
		$a_01_9 = {67 65 74 5f 41 6e 74 69 56 49 6e 66 6f } //1 get_AntiVInfo
		$a_01_10 = {47 65 74 57 65 62 52 65 71 75 65 73 74 } //1 GetWebRequest
		$a_00_11 = {73 00 65 00 74 00 75 00 73 00 65 00 72 00 69 00 6e 00 66 00 6f 00 2e 00 70 00 68 00 70 00 } //5 setuserinfo.php
		$a_00_12 = {75 00 70 00 64 00 61 00 74 00 65 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 69 00 6e 00 66 00 6f 00 2e 00 70 00 68 00 70 00 } //5 updateantivirusinfo.php
		$a_00_13 = {73 00 65 00 74 00 6c 00 61 00 73 00 74 00 73 00 65 00 65 00 6e 00 2e 00 70 00 68 00 70 00 } //5 setlastseen.php
		$a_00_14 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 2e 00 70 00 68 00 70 00 } //5 downloads.php
		$a_00_15 = {73 00 65 00 74 00 75 00 70 00 64 00 61 00 74 00 65 00 64 00 2e 00 70 00 68 00 70 00 } //5 setupdated.php
		$a_00_16 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //5 SELECT * FROM AntiVirusProduct
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_00_11  & 1)*5+(#a_00_12  & 1)*5+(#a_00_13  & 1)*5+(#a_00_14  & 1)*5+(#a_00_15  & 1)*5+(#a_00_16  & 1)*5) >=41
 
}