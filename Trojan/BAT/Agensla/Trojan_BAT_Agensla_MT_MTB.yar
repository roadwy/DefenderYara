
rule Trojan_BAT_Agensla_MT_MTB{
	meta:
		description = "Trojan:BAT/Agensla.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {00 47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d 00 46 72 6f 6d 53 74 72 65 61 6d 00 47 5a 69 70 53 74 72 65 61 6d 00 4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1
		$a_81_1 = {6c 6e 44 49 53 4d 43 6f 6d 6d 69 74 } //1 lnDISMCommit
		$a_81_2 = {52 45 47 45 58 54 4f 4b 45 4e 5f 54 69 6d 65 73 74 61 6d 70 50 72 65 66 69 78 } //1 REGEXTOKEN_TimestampPrefix
		$a_81_3 = {46 6f 72 6d 4c 69 62 2e 42 61 69 64 75 } //1 FormLib.Baidu
		$a_81_4 = {6d 69 6b 65 63 65 6c 37 39 2e 77 6f 72 64 70 72 65 73 73 2e 63 6f 6d } //1 mikecel79.wordpress.com
		$a_81_5 = {63 68 6b 43 61 70 74 75 72 65 56 65 72 69 66 79 } //1 chkCaptureVerify
		$a_81_6 = {2f 4d 6f 75 6e 74 2d 57 49 4d 20 2f 52 65 61 64 4f 6e 6c 79 20 2f 57 69 6d 46 69 6c 65 3a } //1 /Mount-WIM /ReadOnly /WimFile:
		$a_81_7 = {44 61 74 61 20 53 6f 75 72 63 65 3d 31 32 37 2e 30 2e 30 2e 31 3b 49 6e 69 74 69 61 6c 20 43 61 74 61 6c 6f 67 3d 48 61 63 6b 61 74 68 6f 6e 3b 55 73 65 72 20 49 44 3d 73 61 3b 50 61 73 73 77 6f 72 64 3d 76 61 67 72 61 6e 74 } //1 Data Source=127.0.0.1;Initial Catalog=Hackathon;User ID=sa;Password=vagrant
		$a_81_8 = {24 31 30 65 33 30 33 62 36 2d 32 30 63 37 2d 34 38 64 30 2d 38 61 36 61 2d 61 33 65 35 35 38 66 31 36 65 38 30 } //1 $10e303b6-20c7-48d0-8a6a-a3e558f16e80
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=7
 
}