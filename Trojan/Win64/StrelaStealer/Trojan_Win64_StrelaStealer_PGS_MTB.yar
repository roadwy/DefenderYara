
rule Trojan_Win64_StrelaStealer_PGS_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.PGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 6b 68 56 69 75 6c 50 69 71 48 48 4f 45 6f 63 43 76 56 63 69 4c 71 52 54 77 6b 67 77 47 48 63 67 52 54 42 6c 50 4b 6b 6b 41 78 46 56 4c 71 4d 48 7a 46 6c 66 43 41 41 62 67 53 61 63 67 78 65 42 4c 62 4d 79 61 70 78 51 77 4d 54 } //3 mkhViulPiqHHOEocCvVciLqRTwkgwGHcgRTBlPKkkAxFVLqMHzFlfCAAbgSacgxeBLbMyapxQwMT
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}