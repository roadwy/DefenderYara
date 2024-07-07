
rule Trojan_BAT_Tasker_GKH_MTB{
	meta:
		description = "Trojan:BAT/Tasker.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 08 00 fe 0c 0a 00 8f 14 00 00 01 25 71 14 00 00 01 fe 0c 02 00 d2 61 d2 81 14 00 00 01 fe 0c 0a 00 20 ff 00 00 00 5f 3a 14 00 00 00 fe 0c 02 00 fe 0c 02 00 5a 20 b7 5c 8a 00 6a 5e fe 0e 02 00 fe 0c 0a 00 20 01 00 00 00 58 fe 0e 0a 00 fe 0c 0a 00 fe 0c 08 00 8e 69 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}