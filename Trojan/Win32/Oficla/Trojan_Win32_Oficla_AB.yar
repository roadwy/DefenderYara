
rule Trojan_Win32_Oficla_AB{
	meta:
		description = "Trojan:Win32/Oficla.AB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5a 51 48 56 57 45 54 45 5c 54 6b 65 74 6f 77 71 66 61 5c 59 6b 70 64 73 79 73 20 55 56 5c 45 77 72 76 67 6e 61 58 67 74 73 6d 71 6e 5c 44 6b 70 6e 6f 6b 71 6e } //1 ZQHVWETE\Tketowqfa\Ykpdsys UV\EwrvgnaXgtsmqn\Dkpnokqn
		$a_01_1 = {69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}