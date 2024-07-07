
rule BrowserModifier_Win32_KipodToolsCby{
	meta:
		description = "BrowserModifier:Win32/KipodToolsCby,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_01_0 = {4b 69 70 6f 64 54 6f 6f 6c 73 3a 3a 49 45 54 6f 6f 6c 73 3a 3a } //1 KipodTools::IETools::
		$a_01_1 = {54 6f 6f 6c 73 3a 3a 49 45 54 6f 6f 6c 73 3a 3a 60 } //1 Tools::IETools::`
		$a_01_2 = {4b 69 70 6f 64 54 6f 6f 6c 73 5c 4b 69 70 6f 64 54 6f 6f 6c 73 2e 63 70 70 } //1 KipodTools\KipodTools.cpp
		$a_01_3 = {4f 6e 6c 79 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 20 63 6f 64 65 20 73 68 6f 75 6c 64 20 77 72 69 74 65 20 74 68 69 73 } //5 Only Internet Explorer code should write this
		$a_01_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 41 00 70 00 70 00 72 00 6f 00 76 00 65 00 64 00 20 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 } //5 Software\Microsoft\Internet Explorer\Approved Extensions
		$a_01_5 = {56 69 62 65 72 } //-10 Viber
		$a_01_6 = {56 00 69 00 62 00 65 00 72 00 } //-10 Viber
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*-10+(#a_01_6  & 1)*-10) >=11
 
}