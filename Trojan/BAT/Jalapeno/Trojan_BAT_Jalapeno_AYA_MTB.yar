
rule Trojan_BAT_Jalapeno_AYA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 68 72 65 61 64 5f 68 69 6a 61 63 6b 69 6e 67 } //2 Thread_hijacking
		$a_01_1 = {24 30 30 39 61 62 33 61 63 2d 33 37 33 62 2d 34 64 64 62 2d 61 38 66 33 2d 35 41 35 30 44 31 33 32 36 35 45 41 } //1 $009ab3ac-373b-4ddb-a8f3-5A50D13265EA
		$a_01_2 = {54 68 65 41 74 74 61 63 6b 2e 65 78 65 } //1 TheAttack.exe
		$a_01_3 = {50 72 6f 63 65 73 73 49 6e 6a 65 63 74 } //1 ProcessInject
		$a_00_4 = {53 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 64 00 20 00 74 00 68 00 65 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 2e 00 2e 00 } //1 Successfully created the process...
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}