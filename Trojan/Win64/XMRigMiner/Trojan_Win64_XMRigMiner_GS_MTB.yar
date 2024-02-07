
rule Trojan_Win64_XMRigMiner_GS_MTB{
	meta:
		description = "Trojan:Win64/XMRigMiner.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 02 00 "
		
	strings :
		$a_80_0 = {64 6f 6e 61 74 65 2d 6f 76 65 72 2d 70 72 6f 78 79 } //donate-over-proxy  02 00 
		$a_80_1 = {70 6f 6f 6c 73 } //pools  02 00 
		$a_80_2 = {72 69 67 2d 69 64 } //rig-id  02 00 
		$a_80_3 = {6e 6f 70 3d 24 7b 4e 55 4d 42 45 52 5f 4f 46 5f 50 52 4f 43 45 53 53 4f 52 53 7d } //nop=${NUMBER_OF_PROCESSORS}  01 00 
		$a_00_4 = {66 32 70 6f 6f 6c 2e 63 6f 6d } //01 00  f2pool.com
		$a_00_5 = {73 6b 79 70 6f 6f 6c 2e 6f 72 67 } //01 00  skypool.org
		$a_00_6 = {68 61 73 68 76 61 75 6c 74 2e 70 72 6f 6d 6f } //01 00  hashvault.promo
		$a_02_7 = {ff 13 48 83 eb 08 48 39 f3 75 f5 48 8d 0d 90 01 04 48 83 c4 28 5b 5e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}