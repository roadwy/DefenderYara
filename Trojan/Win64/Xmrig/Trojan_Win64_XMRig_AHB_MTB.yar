
rule Trojan_Win64_XMRig_AHB_MTB{
	meta:
		description = "Trojan:Win64/XMRig.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 48 48 81 e1 ?? ?? ?? ?? 0f b6 c9 33 c1 48 8b 4c 24 28 48 8b 54 24 30 48 03 d1 48 8b ca 88 01 e9 } //30
		$a_01_1 = {78 6d 72 5f 6d 69 6e 65 72 5f 64 6c 6c 5f 73 74 61 72 74 } //20 xmr_miner_dll_start
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}