
rule TrojanSpy_Win32_Banker_MF{
	meta:
		description = "TrojanSpy:Win32/Banker.MF,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 65 6d 70 6f 20 64 65 20 69 6e 73 74 61 6c 61 } //1 Tempo de instala
		$a_01_1 = {6d 61 63 20 6e 6f 74 20 66 6f 75 6e 64 } //1 mac not found
		$a_01_2 = {55 73 65 72 73 5c 63 6f 6e 69 73 68 5c 44 65 73 6b 74 6f 70 5c 53 79 73 74 65 6d 61 20 4e 6f 76 6f 20 44 6c 6c 5c 5f 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 70 61 73 } //1 Users\conish\Desktop\Systema Novo Dll\_IEBrowserHelper.pas
		$a_01_3 = {53 4f 4f 50 4e 45 58 54 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 体偏䕎员搮汬䐀汬慃啮汮慯乤睯
		$a_01_4 = {43 3a 20 73 65 72 69 61 6c 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a 20 } //1 C: serial..........: 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}