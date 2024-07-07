
rule TrojanSpy_Win32_Agent_PI{
	meta:
		description = "TrojanSpy:Win32/Agent.PI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 20 53 65 72 76 69 63 65 20 53 75 63 63 65 73 73 2c 52 65 61 64 79 20 45 78 65 63 75 74 65 20 57 6f 72 6b 20 54 68 72 65 61 64 2e 2e 2e } //1 Install Service Success,Ready Execute Work Thread...
		$a_01_1 = {4e 6f 20 46 69 6e 64 20 53 65 72 76 69 63 65 2c 52 65 61 64 79 20 49 6e 73 74 61 6c 6c 20 53 65 72 76 69 63 65 2e 2e 2e } //1 No Find Service,Ready Install Service...
		$a_01_2 = {4e 6f 20 46 69 6e 64 20 52 65 64 47 69 72 6c 20 53 65 72 76 65 72 2c 49 6e 73 74 61 6c 6c 69 6e 67 2e 2e 2e } //1 No Find RedGirl Server,Installing...
		$a_00_3 = {68 74 6d 6c 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 htmlfile\shell\open\command
		$a_01_4 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 64 65 6c 65 74 65 } //1 if exist "%s" goto delete
		$a_01_5 = {21 2a 5f 2a 2d 3e 73 65 76 65 6e 2d 65 6c 65 76 65 6e 3c 2d 2a 5f 2a 21 } //1 !*_*->seven-eleven<-*_*!
		$a_01_6 = {25 73 20 49 6e 6a 65 63 74 20 54 6f 20 42 72 6f 77 73 65 72 2e 2e 2e } //1 %s Inject To Browser...
		$a_01_7 = {5c 74 6d 70 2e 62 61 74 } //1 \tmp.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}