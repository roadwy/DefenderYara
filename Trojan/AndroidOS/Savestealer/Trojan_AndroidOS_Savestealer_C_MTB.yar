
rule Trojan_AndroidOS_Savestealer_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Savestealer.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 73 75 72 66 65 72 73 74 75 62 73 2f 61 75 74 6f 73 74 61 72 74 3b } //01 00  /surferstubs/autostart;
		$a_01_1 = {2f 73 75 72 66 65 72 73 74 75 62 73 2f 54 72 61 63 65 3b } //01 00  /surferstubs/Trace;
		$a_01_2 = {2f 47 72 6f 77 4c 61 75 6e 63 68 65 72 54 72 61 63 65 3b } //01 00  /GrowLauncherTrace;
		$a_01_3 = {73 74 61 72 74 57 61 74 63 68 69 6e 67 } //01 00  startWatching
		$a_01_4 = {6a 6e 69 5f 67 65 74 5f 6d 74 75 } //00 00  jni_get_mtu
	condition:
		any of ($a_*)
 
}