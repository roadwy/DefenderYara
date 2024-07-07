
rule Trojan_BAT_Fsysna_NF_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {6f 47 00 00 0a 74 90 01 03 01 13 03 38 90 01 03 00 dd 90 01 03 ff 38 90 01 03 ff 11 00 11 01 16 11 01 8e 69 6f 90 01 03 0a 90 00 } //5
		$a_01_1 = {54 76 63 78 6e 78 75 75 64 6a 74 6c 6d 72 79 61 6a 64 69 75 75 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Tvcxnxuudjtlmryajdiuur.Properties.Resources
		$a_01_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}