
rule Trojan_AndroidOS_SpyAgent_AL{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.AL,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 61 6b 65 4c 6f 63 6b 45 78 61 6d 70 6c 65 41 70 70 54 61 67 31 } //2 WakeLockExampleAppTag1
		$a_01_1 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 64 61 74 2e 61 38 61 6e 64 6f 73 65 72 76 65 72 78 2e 53 48 55 54 44 4f 57 4e } //2 com.example.dat.a8andoserverx.SHUTDOWN
		$a_01_2 = {53 74 61 72 74 20 52 65 63 6f 72 64 20 6b 6f 6b 6f 6b 6f 6b 6f 6b 6f } //2 Start Record kokokokoko
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}