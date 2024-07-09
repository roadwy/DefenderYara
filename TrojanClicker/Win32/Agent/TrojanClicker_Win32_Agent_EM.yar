
rule TrojanClicker_Win32_Agent_EM{
	meta:
		description = "TrojanClicker:Win32/Agent.EM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 81 38 4d 5a 0f 85 ?? ?? 00 00 8b 45 ?? 8b 40 3c 8b 55 ?? 03 c2 8b 80 80 00 00 00 } //3
		$a_00_1 = {69 70 2e 68 65 74 6f 64 6f 2e 63 6f 6d 3a 38 37 35 34 2f 69 70 2e 70 68 70 } //1 ip.hetodo.com:8754/ip.php
		$a_00_2 = {2e 68 65 74 6f 64 6f 2e 63 6f 6d 3a 38 30 38 30 2f 73 6f 67 6f 75 63 6f 6e 66 69 67 2f 63 6c 69 63 6b 5f 6e 65 77 5f } //1 .hetodo.com:8080/sogouconfig/click_new_
		$a_00_3 = {2f 63 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 } //1 /count.asp?mac=%s&ver=%s
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}