
rule Trojan_BAT_KillWin_SWT_MTB{
	meta:
		description = "Trojan:BAT/KillWin.SWT!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 61 79 6c 6f 61 64 5f 73 74 61 72 74 5f 4c 6f 61 64 } //2 Payload_start_Load
		$a_01_1 = {52 00 45 00 41 00 44 00 59 00 20 00 54 00 4f 00 20 00 44 00 49 00 45 00 3f 00 21 00 } //2 READY TO DIE?!
		$a_01_2 = {74 00 76 00 5f 00 6e 00 6f 00 69 00 73 00 65 00 5f 00 64 00 69 00 72 00 74 00 79 00 } //2 tv_noise_dirty
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}