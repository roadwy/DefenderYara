
rule PWS_Win32_Msnpass_C{
	meta:
		description = "PWS:Win32/Msnpass.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 69 73 74 65 72 4d 73 6e 43 6f 6e 74 61 63 74 73 } //3 listerMsnContacts
		$a_01_1 = {45 00 6e 00 76 00 69 00 61 00 64 00 6f 00 3d 00 } //2 Enviado=
		$a_01_2 = {40 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 6d 00 73 00 6e 00 2e 00 63 00 6f 00 6d 00 20 00 3e 00 } //1 @Microsoft.msn.com >
		$a_01_3 = {40 00 74 00 65 00 72 00 72 00 61 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 3e 00 } //1 @terra.com.br>
		$a_01_4 = {40 00 6f 00 69 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 3e 00 } //1 @oi.com.br>
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}