
rule Trojan_Win32_Smasarch_F{
	meta:
		description = "Trojan:Win32/Smasarch.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 65 72 69 66 79 2e 73 6d 73 73 74 61 74 75 73 2e 63 6f 6d 2f 73 6d 73 2f 69 73 76 61 6c 69 64 32 2e 70 68 70 3f 63 6f 64 65 3d 5c 24 52 30 26 63 6f 75 6e 74 72 79 3d 24 7b 43 4f 55 4e 54 52 59 7d 26 70 72 3d 24 7b 50 52 7d 26 61 66 3d 24 7b 41 46 7d 26 6e 75 6d 3d 24 7b 4e 55 4d 7d } //01 00  verify.smsstatus.com/sms/isvalid2.php?code=\$R0&country=${COUNTRY}&pr=${PR}&af=${AF}&num=${NUM}
		$a_00_1 = {43 75 73 74 6f 6d 20 48 6f 6d 65 3d 68 74 74 70 3a 2f 2f 75 6b 2e 77 6f 6f 66 69 2e 69 6e 66 6f } //01 00  Custom Home=http://uk.woofi.info
		$a_00_2 = {70 61 6e 65 6c 73 6d 73 31 2e 45 6e 67 6c 69 73 68 } //01 00  panelsms1.English
		$a_00_3 = {50 6c 61 74 66 6f 72 6d 20 4b 69 6e 64 3d 73 6d 73 } //00 00  Platform Kind=sms
	condition:
		any of ($a_*)
 
}