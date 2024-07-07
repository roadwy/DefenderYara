
rule Trojan_Win32_NSISInject_BH_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 61 6d 69 74 74 61 73 5c 41 72 6f 6d 61 73 74 6f 66 66 65 72 73 5c 4d 61 72 6b 5c 66 79 72 61 61 62 2e 50 6c 61 } //1 Camittas\Aromastoffers\Mark\fyraab.Pla
		$a_01_1 = {4e 61 76 61 72 72 65 5c 52 65 63 65 70 74 6f 72 73 5c 52 65 66 61 6d 69 6c 69 61 72 69 7a 65 5c 73 70 61 72 74 61 63 69 73 6d 5c 4d 65 72 67 68 2e 59 6f 75 } //1 Navarre\Receptors\Refamiliarize\spartacism\Mergh.You
		$a_01_2 = {42 69 6e 6f 6d 69 6e 6f 75 73 5c 62 6f 72 74 6c 69 63 69 74 65 72 65 72 5c 46 6c 75 67 74 62 69 6c 65 6e 2e 52 65 67 } //1 Binominous\bortliciterer\Flugtbilen.Reg
		$a_01_3 = {42 65 64 73 74 65 62 6f 72 67 65 72 6c 69 67 65 73 5c 4f 73 74 72 61 69 74 65 2e 4c 79 73 } //1 Bedsteborgerliges\Ostraite.Lys
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 41 75 6b 74 69 6f 6e 65 72 73 5c 48 61 6c 76 64 65 6c 73 5c 4e 65 64 6c 67 67 65 6e 64 65 5c 42 65 6c 69 6d 6f 75 73 69 6e 65 64 } //1 Software\Auktioners\Halvdels\Nedlggende\Belimousined
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}