
rule PWS_Win32_Fareit_RP_MTB{
	meta:
		description = "PWS:Win32/Fareit.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 66 6f 6b 70 39 38 32 42 66 75 } //1 Cfokp982Bfu
		$a_01_1 = {68 74 74 70 3a 2f 2f 62 75 74 74 65 72 63 68 6f 63 6f 2e 6e 65 74 2f 61 64 6d 69 6e 2f 62 75 6c 6c 2f 67 61 74 65 2e 70 68 70 } //1 http://butterchoco.net/admin/bull/gate.php
		$a_01_2 = {59 55 49 50 57 44 46 49 4c 45 30 59 55 49 50 4b 44 46 49 4c 45 30 59 55 49 43 52 59 50 54 45 44 30 59 55 49 31 2e 30 } //1 YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0
		$a_01_3 = {7b 37 34 46 46 31 37 33 30 2d 42 31 46 32 2d 34 44 38 38 2d 39 32 36 42 2d 31 35 36 38 46 41 45 36 31 44 42 37 7d } //1 {74FF1730-B1F2-4D88-926B-1568FAE61DB7}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}