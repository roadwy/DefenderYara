
rule Trojan_AndroidOS_Arsink_H_MTB{
	meta:
		description = "Trojan:AndroidOS/Arsink.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 6c 6c 43 61 6c 6c 73 48 69 73 74 6f 74 79 } //1 getAllCallsHistoty
		$a_01_1 = {48 61 63 6b 65 64 20 42 79 20 53 69 73 75 72 79 61 4f 66 66 69 63 69 61 6c } //2 Hacked By SisuryaOfficial
		$a_01_2 = {63 61 6c 6c 64 6d 70 70 } //2 calldmpp
		$a_01_3 = {2f 73 74 6f 72 61 67 65 2f 65 6d 75 6c 61 74 65 64 2f 30 2f 2e 48 61 63 6b 65 64 42 79 53 75 72 79 61 2f } //2 /storage/emulated/0/.HackedBySurya/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=7
 
}