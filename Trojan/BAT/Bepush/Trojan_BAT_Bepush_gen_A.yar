
rule Trojan_BAT_Bepush_gen_A{
	meta:
		description = "Trojan:BAT/Bepush.gen!A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {2f 65 78 74 46 69 6c 65 73 2f 63 6f 6e 74 72 6f 6c } //1 /extFiles/control
		$a_01_1 = {5c 53 45 78 74 65 6e 73 69 6f 6e } //1 \SExtension
		$a_01_2 = {57 65 62 43 6c 69 65 6e 74 20 46 6f 72 20 45 78 74 65 6e 73 69 6f 6e 73 } //1 WebClient For Extensions
		$a_01_3 = {46 4c 56 50 6c 61 79 2e 65 78 65 } //1 FLVPlay.exe
		$a_01_4 = {46 4c 56 55 70 64 61 74 65 } //1 FLVUpdate
		$a_01_5 = {61 67 65 6e 74 6f 66 65 78 2e 63 6f 6d } //1 agentofex.com
		$a_01_6 = {65 6b 6c 65 6e 74 69 64 75 6e 79 61 73 69 2e 63 6f 6d } //1 eklentidunyasi.com
		$a_01_7 = {65 6e 6f 74 69 63 65 72 2e 63 6f 6d } //1 enoticer.com
		$a_01_8 = {73 68 6f 77 6d 61 73 6b 6f 6e 6e 6e 2e 63 6f 6d } //1 showmaskonnn.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}
rule Trojan_BAT_Bepush_gen_A_2{
	meta:
		description = "Trojan:BAT/Bepush.gen!A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 0b 00 00 "
		
	strings :
		$a_01_0 = {76 65 72 73 69 6f 6e 22 2e 2a 3f 3a 2e 2a 3f 22 28 2e 2a 3f 29 } //1 version".*?:.*?"(.*?)
		$a_01_1 = {3c 65 6d 3a 69 64 3e 28 2e 2a 3f 29 3c 2f 65 6d 3a 69 64 3e } //1 <em:id>(.*?)</em:id>
		$a_01_2 = {72 65 73 74 6f 72 65 5f 6f 6e 5f 73 74 61 72 74 75 70 } //1 restore_on_startup
		$a_01_3 = {61 63 6b 5f 70 72 6f 6d 70 74 5f 63 6f 75 6e 74 } //1 ack_prompt_count
		$a_01_4 = {43 68 72 6f 6d 65 20 65 78 74 65 6e 73 69 6f 6e 20 7b 30 7d } //1 Chrome extension {0}
		$a_01_5 = {46 69 72 65 66 6f 78 20 65 78 74 65 6e 73 69 6f 6e 20 7b 30 7d } //1 Firefox extension {0}
		$a_01_6 = {5c 43 68 72 6f 6d 65 5c 45 78 74 65 6e 73 69 6f 6e 73 } //1 \Chrome\Extensions
		$a_01_7 = {5c 46 69 72 65 66 6f 78 5c 45 78 74 65 6e 73 69 6f 6e 73 } //1 \Firefox\Extensions
		$a_01_8 = {5c 53 45 78 74 65 6e 73 69 6f 6e } //1 \SExtension
		$a_01_9 = {52 65 67 20 64 65 6e 65 6d 65 2e 2e 2e } //1 Reg deneme...
		$a_01_10 = {43 72 65 61 74 65 20 6c 6f 67 31 32 33 2e 2e 2e } //1 Create log123...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=8
 
}