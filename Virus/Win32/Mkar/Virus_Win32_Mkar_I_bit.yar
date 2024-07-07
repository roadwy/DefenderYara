
rule Virus_Win32_Mkar_I_bit{
	meta:
		description = "Virus:Win32/Mkar.I!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 72 61 6b } //1 SOFTWARE\Microsoft\Mrak
		$a_01_1 = {5c 4e 65 74 73 74 61 72 74 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //2 \Netstart\svchost.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}