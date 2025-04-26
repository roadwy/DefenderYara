
rule Trojan_Win32_Hescrel_A{
	meta:
		description = "Trojan:Win32/Hescrel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 3d 72 09 0a 49 } //1 㵙ॲ䤊
		$a_03_1 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 73 00 63 00 72 00 [0-0a] 73 00 63 00 72 00 2e 00 6c 00 6e 00 6b 00 } //1
		$a_03_2 = {52 74 6c 49 c7 45 ?? 6e 69 74 41 c7 45 ?? 6e 73 69 53 c7 45 ?? 74 72 69 6e 66 c7 ?? e8 67 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}