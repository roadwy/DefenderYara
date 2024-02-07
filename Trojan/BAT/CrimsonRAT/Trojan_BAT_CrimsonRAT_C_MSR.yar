
rule Trojan_BAT_CrimsonRAT_C_MSR{
	meta:
		description = "Trojan:BAT/CrimsonRAT.C!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 2e 31 38 39 2e 31 33 34 2e 32 31 36 } //01 00  5.189.134.216
		$a_00_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 7c 00 74 00 68 00 6e 00 61 00 76 00 69 00 77 00 61 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run|thnaviwa
		$a_01_2 = {62 64 73 73 3d 42 69 74 20 44 65 66 65 6e 64 65 72 2c 6f 6e 6c 69 6e 65 6e 74 3d 51 48 65 61 6c 2c 62 64 61 67 65 6e 74 3d 42 44 20 41 67 65 6e 74 2c 6d 73 73 65 63 65 73 3d 4d 53 20 45 73 73 65 6e 74 69 61 6c 73 2c 66 73 73 6d 33 32 3d 46 53 65 63 75 72 65 2c 61 76 70 3d 4b 61 73 70 65 72 73 6b 79 } //01 00  bdss=Bit Defender,onlinent=QHeal,bdagent=BD Agent,msseces=MS Essentials,fssm32=FSecure,avp=Kaspersky
		$a_01_3 = {44 65 62 75 67 5c 74 68 6e 61 76 69 77 61 2e 70 64 62 } //00 00  Debug\thnaviwa.pdb
	condition:
		any of ($a_*)
 
}