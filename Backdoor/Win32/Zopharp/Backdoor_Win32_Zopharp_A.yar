
rule Backdoor_Win32_Zopharp_A{
	meta:
		description = "Backdoor:Win32/Zopharp.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {72 65 71 75 69 72 65 5f 6f 6e 63 65 28 27 46 75 6e 63 74 69 6f 6e 73 2f 5a 6f 6d 62 69 65 73 2e 70 68 70 27 29 3b } //1 require_once('Functions/Zombies.php');
		$a_01_1 = {72 65 71 75 69 72 65 5f 6f 6e 63 65 28 27 46 75 6e 63 74 69 6f 6e 73 2f 50 68 61 72 6d 69 6e 67 2e 70 68 70 27 29 3b } //1 require_once('Functions/Pharming.php');
		$a_01_2 = {66 69 6c 65 28 55 72 6c 53 65 72 76 65 72 20 2e 20 22 2f 41 64 6d 69 6e 2f 46 75 6e 63 74 69 6f 6e 73 43 6c 69 65 6e 74 2f 53 65 6c 65 63 74 2e 70 68 70 3f 61 63 74 69 6f 6e 31 3d 22 2e 24 41 2e 22 26 61 63 74 69 6f 6e 32 3d 22 2e 24 42 2e 22 26 61 63 74 69 6f 6e 33 3d 22 2e 24 43 29 3b } //1 file(UrlServer . "/Admin/FunctionsClient/Select.php?action1=".$A."&action2=".$B."&action3=".$C);
		$a_01_3 = {24 5a 6f 6d 62 69 65 73 20 3d 20 63 72 65 61 74 65 41 72 72 61 79 28 27 7a 6f 6d 62 69 73 27 20 2c 20 4e 61 6d 65 4d 61 71 75 69 6e 61 20 2c 20 27 6e 61 6d 65 27 29 3b } //1 $Zombies = createArray('zombis' , NameMaquina , 'name');
		$a_01_4 = {43 68 61 74 57 6e 64 2e 53 65 6e 64 4d 65 73 73 61 67 65 28 4d 65 6e 73 61 6a 65 73 5b 52 61 6e 64 6f 6d 5d 29 3b } //1 ChatWnd.SendMessage(Mensajes[Random]);
		$a_01_5 = {66 6f 70 65 6e 20 28 20 22 63 3a 2f 77 69 6e 64 6f 77 73 2f 73 79 73 74 65 6d 33 32 2f 64 72 69 76 65 72 73 2f 65 74 63 2f 68 6f 73 74 73 22 2c 20 22 61 2b 22 20 29 3b } //1 fopen ( "c:/windows/system32/drivers/etc/hosts", "a+" );
		$a_01_6 = {66 6f 70 65 6e 28 24 48 20 2e 20 22 53 63 72 69 70 74 73 2f 46 61 63 65 62 6f 6f 6b 2f 46 61 63 65 62 6f 6f 6b 2e 74 78 74 22 20 2c 20 22 61 2b 22 29 3b } //1 fopen($H . "Scripts/Facebook/Facebook.txt" , "a+");
		$a_01_7 = {66 6f 70 65 6e 28 55 72 6c 53 65 72 76 65 72 20 2e 20 22 2f 41 64 6d 69 6e 2f 46 75 6e 63 74 69 6f 6e 73 43 6c 69 65 6e 74 2f 55 70 64 61 74 65 2e 70 68 70 3f 22 20 2e 20 24 55 72 6c 20 20 2c 20 27 72 27 29 3b } //1 fopen(UrlServer . "/Admin/FunctionsClient/Update.php?" . $Url  , 'r');
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}