
rule Ransom_AndroidOS_SimpLock_B{
	meta:
		description = "Ransom:AndroidOS/SimpLock.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 65 62 75 68 61 34 61 2e 6e 65 74 2f 6b 65 79 73 2f } //01 00  //ebuha4a.net/keys/
		$a_01_1 = {43 61 72 64 53 76 53 74 2e 6a 61 76 61 } //01 00  CardSvSt.java
		$a_01_2 = {4c 61 6e 64 72 6f 69 64 2f 6f 73 2f 50 6f 77 65 72 4d 61 6e 61 67 65 72 24 57 61 6b 65 4c 6f 63 6b 3b } //01 00  Landroid/os/PowerManager$WakeLock;
		$a_01_3 = {4c 6d 79 2f 73 68 61 72 61 67 61 2f 6c 6f 63 6b 65 72 2f 42 75 69 6c 64 43 6f 6e 66 69 67 3b } //00 00  Lmy/sharaga/locker/BuildConfig;
	condition:
		any of ($a_*)
 
}