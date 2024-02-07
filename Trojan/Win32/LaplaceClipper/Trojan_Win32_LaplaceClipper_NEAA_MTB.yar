
rule Trojan_Win32_LaplaceClipper_NEAA_MTB{
	meta:
		description = "Trojan:Win32/LaplaceClipper.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {4f 53 46 52 53 43 4b 54 } //05 00  OSFRSCKT
		$a_01_1 = {42 4e 4b 42 50 4e 48 58 } //02 00  BNKBPNHX
		$a_01_2 = {73 6b 69 70 61 63 74 69 76 65 78 72 65 67 } //02 00  skipactivexreg
		$a_01_3 = {2f 62 75 67 63 68 65 63 6b 66 75 6c 6c } //02 00  /bugcheckfull
		$a_01_4 = {2f 63 68 65 63 6b 70 72 6f 74 65 63 74 69 6f 6e } //02 00  /checkprotection
		$a_01_5 = {39 2f 66 6f 72 63 65 72 75 6e } //02 00  9/forcerun
		$a_01_6 = {33 53 4f 46 54 57 41 52 45 5c 57 69 6e 4c 69 63 65 6e 73 65 } //02 00  3SOFTWARE\WinLicense
		$a_01_7 = {44 00 61 00 74 00 65 00 3a 00 20 00 30 00 33 00 2f 00 31 00 39 00 2f 00 30 00 39 00 20 00 32 00 32 00 3a 00 35 00 } //00 00  Date: 03/19/09 22:5
	condition:
		any of ($a_*)
 
}