
rule Trojan_Win64_Cerbu_AHF_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.AHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 2d 20 43 52 59 50 54 4f 20 57 41 4c 4c 45 54 53 20 2d 2d 2d } //10 --- CRYPTO WALLETS ---
		$a_01_1 = {5b 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 5b 46 4f 52 45 4e 53 49 43 5d 20 20 20 45 78 74 72 61 63 74 69 6e 67 20 53 74 65 61 6d 20 74 6f 6b 65 6e 73 20 66 72 6f 6d 20 4c 65 76 65 6c 44 42 2e 2e 2e } //20 [%02d:%02d:%02d] [FORENSIC]   Extracting Steam tokens from LevelDB...
		$a_01_2 = {5b 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 5b 46 4f 52 45 4e 53 49 43 5d 20 20 20 56 53 53 20 73 6e 61 70 73 68 6f 74 20 64 65 6c 65 74 65 64 } //30 [%02d:%02d:%02d] [FORENSIC]   VSS snapshot deleted
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30) >=60
 
}