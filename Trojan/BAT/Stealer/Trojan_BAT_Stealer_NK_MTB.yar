
rule Trojan_BAT_Stealer_NK_MTB{
	meta:
		description = "Trojan:BAT/Stealer.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_03_0 = {06 02 6f 05 01 00 0a 6f ?? ?? ?? 0a 06 7e ?? ?? ?? 04 74 ?? ?? ?? 01 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a } //5
		$a_01_1 = {73 65 74 5f 55 73 65 4d 61 63 68 69 6e 65 4b 65 79 53 74 6f 72 65 } //1 set_UseMachineKeyStore
		$a_01_2 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //1 Debugger Detected
		$a_01_3 = {49 4a 6e 53 78 55 66 64 37 49 } //1 IJnSxUfd7I
		$a_01_4 = {52 75 6e 74 61 6d 65 20 42 72 61 6b 6f 72 } //1 Runtame Brakor
		$a_01_5 = {74 79 70 65 6d 64 74 } //1 typemdt
		$a_01_6 = {63 6c 61 73 73 74 68 69 73 } //1 classthis
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=11
 
}