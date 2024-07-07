
rule Misleading_iPhoneOS_Tracer_A_xp{
	meta:
		description = "Misleading:iPhoneOS/Tracer.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 50 68 6f 6e 65 20 44 65 76 65 6c 6f 70 65 72 3a 20 6d 6f 75 72 61 64 20 62 65 6e 20 61 79 65 64 } //1 iPhone Developer: mourad ben ayed
		$a_00_1 = {25 73 5b 4c 25 64 5d 20 5b 25 40 5d 20 55 70 6c 6f 61 64 20 56 49 44 45 4f } //1 %s[L%d] [%@] Upload VIDEO
		$a_00_2 = {25 73 5b 4c 25 64 5d 20 5b 25 40 5d 20 2b 42 65 67 69 6e 20 72 65 63 6f 72 64 69 6e 67 } //1 %s[L%d] [%@] +Begin recording
		$a_00_3 = {63 6f 6d 2e 74 69 6d 65 63 6f 6d 70 69 6c 65 72 2e 72 65 63 6f 72 64 65 72 } //1 com.timecompiler.recorder
		$a_00_4 = {2f 76 61 72 2f 6d 6f 62 69 6c 65 2f 54 72 61 63 65 72 2f 63 61 6c 6c 5f 68 69 73 74 6f 72 79 2e 64 62 } //1 /var/mobile/Tracer/call_history.db
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}