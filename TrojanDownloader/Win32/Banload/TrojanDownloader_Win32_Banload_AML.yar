
rule TrojanDownloader_Win32_Banload_AML{
	meta:
		description = "TrojanDownloader:Win32/Banload.AML,SIGNATURE_TYPE_PEHSTR_EXT,ffffffee 02 ffffffd5 02 08 00 00 "
		
	strings :
		$a_01_0 = {56 7e 65 21 72 7e 73 21 69 7e 6f 21 6e 5e 5c 5e 52 7e 75 21 6e 7e } //300 V~e!r~s!i~o!n^\^R~u!n~
		$a_01_1 = {7e 63 2b 68 5e 61 7e 76 7e 65 21 3d 21 78 21 63 2b 68 7e 61 7e 76 7e 65 21 } //300 ~c+h^a~v~e!=!x!c+h~a~v~e!
		$a_01_2 = {21 68 5e 74 7e 74 7e 70 2b 3a 5e 2f 7e 2f 21 62 21 6c 2b 61 21 63 7e 6b 21 61 2b 6e 7e 64 7e 77 7e 68 7e 69 2b 74 5e 65 7e 78 5e 2e 5e 63 7e 6f 21 6d } //100 !h^t~t~p+:^/~/!b!l+a!c~k!a+n~d~w~h~i+t^e~x^.^c~o!m
		$a_01_3 = {7e 45 5e 53 21 45 21 54 7e 20 7e 43 7e 6c 2b 69 5e 65 21 6e 7e 74 } //50 ~E^S!E!T~ ~C~l+i^e!n~t
		$a_01_4 = {72 21 78 21 39 21 2f 21 21 77 5e 78 7e 31 21 7e 2e 7e 6a 2b 70 5e 67 } //50 r!x!9!/!!w^x~1!~.~j+p^g
		$a_01_5 = {76 7e 32 21 35 5e 2f 21 72 21 78 21 39 21 2f 21 2b 77 2b 78 7e 36 21 7e 2e 7e 6a 2b 70 5e 67 } //50 v~2!5^/!r!x!9!/!+w+x~6!~.~j+p^g
		$a_01_6 = {7e 52 5e 75 21 6e 5e 44 2b 4c 5e 4c 5e 33 7e 32 5e 2e 7e 65 7e 78 5e 65 } //25 ~R^u!n^D+L^L^3~2^.~e~x^e
		$a_01_7 = {21 77 5e 78 7e 31 21 2b 2e 7e 63 2b 70 7e 6c } //25 !w^x~1!+.~c+p~l
	condition:
		((#a_01_0  & 1)*300+(#a_01_1  & 1)*300+(#a_01_2  & 1)*100+(#a_01_3  & 1)*50+(#a_01_4  & 1)*50+(#a_01_5  & 1)*50+(#a_01_6  & 1)*25+(#a_01_7  & 1)*25) >=725
 
}