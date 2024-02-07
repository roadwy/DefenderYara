
rule Trojan_Win64_CoinMiner_RC_bit{
	meta:
		description = "Trojan:Win64/CoinMiner.RC!bit,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 } //01 00  shutdown -s -t
		$a_01_1 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e } //01 00  schtasks /create /tn
		$a_01_2 = {2d 2d 6d 61 78 2d 63 70 75 2d 75 73 61 67 65 3d } //01 00  --max-cpu-usage=
		$a_01_3 = {2d 2d 63 75 64 61 2d 62 66 61 63 74 6f 72 3d 31 32 } //01 00  --cuda-bfactor=12
		$a_01_4 = {69 6e 68 65 72 69 74 61 6e 63 65 3a 65 20 2f 64 65 6e 79 20 22 53 59 53 54 45 4d 3a 28 52 2c 52 45 41 2c 52 41 2c 52 44 29 } //01 00  inheritance:e /deny "SYSTEM:(R,REA,RA,RD)
		$a_01_5 = {68 74 74 70 73 3a 2f 2f 32 6e 6f 2e 63 6f } //01 00  https://2no.co
		$a_01_6 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 41 64 76 61 6e 63 65 64 20 54 68 72 65 61 74 20 50 72 6f 74 65 63 74 69 6f 6e 5c 4d 73 53 65 6e 73 65 2e 65 78 65 } //01 00  Program Files\Windows Defender Advanced Threat Protection\MsSense.exe
		$a_01_7 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 43 6f 6e 66 69 67 53 65 63 75 72 69 74 79 50 6f 6c 69 63 79 2e 65 78 65 } //00 00  Program Files\Windows Defender\ConfigSecurityPolicy.exe
	condition:
		any of ($a_*)
 
}