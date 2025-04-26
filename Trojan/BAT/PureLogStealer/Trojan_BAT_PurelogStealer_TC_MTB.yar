
rule Trojan_BAT_PurelogStealer_TC_MTB{
	meta:
		description = "Trojan:BAT/PurelogStealer.TC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 63 68 69 72 72 65 65 69 72 6c 2e 63 6f 6d 2f 77 70 2d 70 61 6e 65 6c 2f 75 70 6c 6f 61 64 73 2f 57 6c 76 64 6c 69 76 73 2e 6d 70 33 } //2 https://www.chirreeirl.com/wp-panel/uploads/Wlvdlivs.mp3
		$a_81_1 = {73 58 67 62 7a 6a 2b 6d 6b 70 43 36 39 43 37 4a 76 63 50 33 73 51 3d 3d } //1 sXgbzj+mkpC69C7JvcP3sQ==
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}